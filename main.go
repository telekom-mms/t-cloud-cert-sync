package main

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/opentelekomcloud/gophertelekomcloud"
	"github.com/opentelekomcloud/gophertelekomcloud/openstack"
	"github.com/opentelekomcloud/gophertelekomcloud/openstack/elb/v3/certificates"
	"github.com/opentelekomcloud/gophertelekomcloud/openstack/elb/v3/listeners"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
)

const (
	AnnotationListenerID  = "t-cloud.telekom.com/listener-id"
	AnnotationSyncedState = "t-cloud.telekom.com/synced-state" // NEW: persistent memory
	// AnnotationListenerSlot selects the listener slot: "default" (default_tls_container_ref, the
	// default when unset) or "sni" (one entry in sni_container_refs, leaving the others untouched).
	AnnotationListenerSlot = "t-cloud.telekom.com/listener-slot"
	// AnnotationCertificateID records the ELB certificate the controller last bound for the Secret,
	// so an SNI rotation replaces exactly that entry.
	AnnotationCertificateID = "t-cloud.telekom.com/certificate-id"

	SlotDefault = "default"
	SlotSNI     = "sni"

	// EnvKeepCertRegex names the env var holding the regex of certificate names to keep on cleanup.
	EnvKeepCertRegex     = "KEEP_CERT_REGEX"
	DefaultKeepCertRegex = "dummy"

	// EnvWatchNamespace restricts the controller to the Secrets of one namespace; empty watches all.
	EnvWatchNamespace = "WATCH_NAMESPACE"
)

// thread-safe cache for the certificate hashes/states
var certHashes sync.Map

// keepCertRegex matches certificate names that must be kept during cleanup, even if unused.
// Compiled once at startup, read-only afterwards.
var keepCertRegex *regexp.Regexp

func keepCertPattern() string {
	pattern := os.Getenv(EnvKeepCertRegex)
	if pattern == "" {
		return DefaultKeepCertRegex
	}
	return pattern
}

func shouldDeleteOldCertificate(cert *certificates.Certificate, lookupErr error, pattern *regexp.Regexp) bool {
	return lookupErr == nil && cert != nil && !pattern.MatchString(cert.Name)
}

func listenerSlot(annotations map[string]string) (string, error) {
	switch slot := annotations[AnnotationListenerSlot]; slot {
	case "", SlotDefault:
		return SlotDefault, nil
	case SlotSNI:
		return SlotSNI, nil
	default:
		return "", fmt.Errorf("unsupported %s %q, use %q or %q", AnnotationListenerSlot, slot, SlotDefault, SlotSNI)
	}
}

// syncState keeps the original format for the default slot, so an upgrade does not re-upload every
// certificate that is already in sync.
func syncState(certData []byte, listenerID, slot string) string {
	state := fmt.Sprintf("%x-%s", sha256.Sum256(certData), listenerID)
	if slot == SlotSNI {
		state += "-" + SlotSNI
	}
	return state
}

func certNamePrefix(secretName string) string {
	return "k8s-" + secretName + "-"
}

// certificateDomains returns the DNS names of the leaf (first) certificate in tls.crt; ELB requires them on
// SNI certificates.
func certificateDomains(certPEM []byte) ([]string, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, errors.New("tls.crt contains no PEM certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse tls.crt: %w", err)
	}
	if len(cert.DNSNames) == 0 {
		return nil, errors.New("certificate has no DNS subject alternative names")
	}
	return cert.DNSNames, nil
}

// ownedSNICertificate finds the SNI entry this Secret bound before: the recorded ID, or, when that
// annotation is missing or stale (e.g. its patch failed), the entry named like this Secret's uploads.
func ownedSNICertificate(entries []certificates.Certificate, recordedID, secretName string) string {
	ownName := regexp.MustCompile("^" + regexp.QuoteMeta(certNamePrefix(secretName)) + `\d+$`)
	byName := ""
	for _, cert := range entries {
		if recordedID != "" && cert.ID == recordedID {
			return cert.ID
		}
		if byName == "" && ownName.MatchString(cert.Name) {
			byName = cert.ID
		}
	}
	return byName
}

// sniRefsForUpdate drops this Secret's previous certificate and every other SNI certificate sharing a
// domain with the new one (ELB requires unique SNI domains), keeps the rest in order and appends newID.
// It also returns the dropped foreign certificates; they are only unbound, not deleted.
func sniRefsForUpdate(entries []certificates.Certificate, ownID, newID string, domains []string) (refs, unbound []string) {
	for _, cert := range entries {
		switch {
		case cert.ID == ownID:
		case sharesDomain(cert.Domain, domains):
			unbound = append(unbound, cert.ID)
		default:
			refs = append(refs, cert.ID)
		}
	}
	return append(refs, newID), unbound
}

// sharesDomain reports whether the comma-separated ELB domain list contains one of domains.
func sharesDomain(domainList string, domains []string) bool {
	for _, listed := range strings.Split(domainList, ",") {
		for _, domain := range domains {
			if strings.EqualFold(strings.TrimSpace(listed), domain) {
				return true
			}
		}
	}
	return false
}

func getCertificates(client *golangsdk.ServiceClient, ids []string) ([]certificates.Certificate, error) {
	result := make([]certificates.Certificate, 0, len(ids))
	for _, id := range ids {
		cert, err := certificates.Get(client, id).Extract()
		if err != nil {
			return nil, fmt.Errorf("get SNI certificate %s: %w", id, err)
		}
		result = append(result, *cert)
	}
	return result, nil
}

// warnShadowingSNICertificates only logs: SNI entries matching the default certificate's names take
// precedence for SNI clients, and a previous default that is still an SNI entry cannot be deleted.
func warnShadowingSNICertificates(client *golangsdk.ServiceClient, sniRefs []string, certData []byte, cacheKey, listenerID string) {
	if len(sniRefs) == 0 {
		return
	}
	domains, err := certificateDomains(certData)
	if err != nil {
		log.Printf("Warning: Unable to read the domain names of %s, skipping the SNI overlap check: %v", cacheKey, err)
		return
	}
	entries, err := getCertificates(client, sniRefs)
	if err != nil {
		log.Printf("Warning: Unable to read the SNI certificates of listener %s, skipping the SNI overlap check: %v", listenerID, err)
		return
	}
	for _, cert := range entries {
		if sharesDomain(cert.Domain, domains) {
			log.Printf("Warning: SNI certificate %s (name %q, domains %q) on listener %s shares a domain name with the default certificate from %s; ELB serves the SNI certificate for that name.", cert.ID, cert.Name, cert.Domain, listenerID, cacheKey)
		}
	}
}

func syncedAnnotationsPatch(state, certificateID string) ([]byte, error) {
	return json.Marshal(map[string]any{
		"metadata": map[string]any{
			"annotations": map[string]string{
				AnnotationSyncedState:   state,
				AnnotationCertificateID: certificateID,
			},
		},
	})
}

func main() {
	log.Println("Starting T Cloud Public ELB Cert Sync Controller...")

	// 0. compile the "keep certificate" regex used during cleanup
	keepCertPattern := keepCertPattern()
	var err error
	keepCertRegex, err = regexp.Compile(keepCertPattern)
	if err != nil {
		log.Fatalf("Invalid %s regex %q: %v", EnvKeepCertRegex, keepCertPattern, err)
	}
	log.Printf("Certificates matching %q (%s) will be kept on cleanup, even if unused.", keepCertPattern, EnvKeepCertRegex)

	// 1. init K8s client
	k8sConfig, err := rest.InClusterConfig()
	if err != nil {
		log.Fatalf("Error loading k8s config: %v", err)
	}
	clientset, err := kubernetes.NewForConfig(k8sConfig)
	if err != nil {
		log.Fatalf("Error creating the k8s clients: %v", err)
	}

	// 2. init t cloud client (pure AK/SK, does no IAM-Token)
	provider, err := openstack.NewClient(os.Getenv("OS_AUTH_URL"))
	if err != nil {
		log.Fatalf("Error creating the base client: %v", err)
	}

	provider.AKSKAuthOptions = golangsdk.AKSKAuthOptions{
		AccessKey: os.Getenv("OS_ACCESS_KEY"),
		SecretKey: os.Getenv("OS_SECRET_KEY"),
		ProjectId: os.Getenv("OS_PROJECT_ID"),
	}

	// 3. setup ELB Service Client
	elbEndpoint := fmt.Sprintf("https://elb.%s.otc.t-systems.com/v3/%s/elb/", os.Getenv("OS_REGION_NAME"), os.Getenv("OS_PROJECT_ID"))
	elbClient := &golangsdk.ServiceClient{
		ProviderClient: provider,
		Endpoint:       elbEndpoint,
		MoreHeaders: map[string]string{
			"X-Project-Id": os.Getenv("OS_PROJECT_ID"),
		},
	}

	// 4. K8s informer setup (all namespaces, or only WATCH_NAMESPACE)
	watchNamespace := os.Getenv(EnvWatchNamespace)
	var informerOptions []informers.SharedInformerOption
	if watchNamespace == "" {
		log.Println("Watching Secrets in all namespaces.")
	} else {
		log.Printf("Watching Secrets in namespace %q only (%s).", watchNamespace, EnvWatchNamespace)
		informerOptions = append(informerOptions, informers.WithNamespace(watchNamespace))
	}
	factory := informers.NewSharedInformerFactoryWithOptions(clientset, time.Hour*12, informerOptions...)
	secretInformer := factory.Core().V1().Secrets().Informer()

	secretInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			// WE PASS clientset HERE TO ALLOW PATCHING
			handleSecretChange(clientset, obj, elbClient)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			// WE PASS clientset HERE TO ALLOW PATCHING
			handleSecretChange(clientset, newObj, elbClient)
		},
	})

	// 5. start controller
	stopCh := make(chan struct{})
	defer close(stopCh)

	go factory.Start(stopCh)

	if !cache.WaitForCacheSync(stopCh, secretInformer.HasSynced) {
		log.Fatal("Timed out waiting for caches to sync")
	}

	log.Println("Controller running and waiting for secret events...")

	// graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	log.Println("Stopping controller...")
}

func handleSecretChange(k8sClient *kubernetes.Clientset, obj interface{}, elbClient *golangsdk.ServiceClient) {
	secret, ok := obj.(*corev1.Secret)
	if !ok {
		return
	}

	// check if annotations exists
	listenerID, hasAnnotation := secret.Annotations[AnnotationListenerID]
	if !hasAnnotation || listenerID == "" {
		return // secret is not marked for t cloud
	}

	certData := secret.Data["tls.crt"]
	keyData := secret.Data["tls.key"]

	if len(certData) == 0 || len(keyData) == 0 {
		log.Printf("Warning: secret %s/%s has annotation, but no tls data.", secret.Namespace, secret.Name)
		return
	}

	// calculcate unambiguous state (certificate hash + listener ID + slot)
	cacheKey := fmt.Sprintf("%s/%s", secret.Namespace, secret.Name)
	slot, err := listenerSlot(secret.Annotations)
	if err != nil {
		log.Printf("Warning: secret %s: %v", cacheKey, err)
		return
	}
	currentState := syncState(certData, listenerID, slot)

	// --- 1. CHECK MEMORY CACHE (for fast runtime checks) ---
	lastState, stateExists := certHashes.Load(cacheKey)
	if stateExists && lastState == currentState {
		return
	}

	// --- 2. CHECK PERSISTENT STATE (survives pod restarts) ---
	if secret.Annotations[AnnotationSyncedState] == currentState {
		// Was already synced before a pod restart.
		// Just load into memory to avoid unnecessary API calls.
		certHashes.Store(cacheKey, currentState)
		return
	}

	log.Printf("Change in certificate in %s/%s recognized! processing listener %s (%s slot)...", secret.Namespace, secret.Name, listenerID, slot)

	// SNI certificates must carry their domain names in ELB
	var sniDomains []string
	if slot == SlotSNI {
		sniDomains, err = certificateDomains(certData)
		if err != nil {
			log.Printf("Error: Unable to read the domain names of %s for SNI: %v", cacheKey, err)
			return
		}
	}

	// 1. get current listener state to find OLD certificate
	var oldCertID string
	var sniEntries []certificates.Certificate
	currentListener, err := listeners.Get(elbClient, listenerID).Extract()
	if err != nil || currentListener == nil {
		if slot == SlotSNI {
			// Without the current SNI list, an update would drop every other host's certificate.
			log.Printf("Error: Unable to retrieve listener %s, skipping SNI sync of %s: %v", listenerID, cacheKey, err)
			return
		}
		log.Printf("Warning: Unable to retrieve the current listener state (perhaps it doesn't exist?): %v", err)
	} else if slot == SlotDefault {
		oldCertID = currentListener.DefaultTlsContainerRef
		warnShadowingSNICertificates(elbClient, currentListener.SniContainerRefs, certData, cacheKey, listenerID)
	} else {
		sniEntries, err = getCertificates(elbClient, currentListener.SniContainerRefs)
		if err != nil {
			log.Printf("Error: Unable to read the SNI certificates of listener %s, skipping SNI sync of %s: %v", listenerID, cacheKey, err)
			return
		}
		oldCertID = ownedSNICertificate(sniEntries, secret.Annotations[AnnotationCertificateID], secret.Name)
	}

	// 2. create NEW certificate in t cloud
	certName := fmt.Sprintf("%s%d", certNamePrefix(secret.Name), time.Now().Unix())
	certCreateOpts := certificates.CreateOpts{
		Name:        certName,
		Domain:      strings.Join(sniDomains, ","),
		Certificate: string(certData),
		PrivateKey:  string(keyData),
	}

	newCert, err := certificates.Create(elbClient, certCreateOpts).Extract()
	if err != nil {
		log.Printf("Error uploading the new certificate %s to T Cloud Public: %v", cacheKey, err)
		return
	}
	log.Printf("New certificate created in T Cloud Public. ID: %s", newCert.ID)

	// 3. bind NEW certificate to listener
	listenerUpdateOpts := listeners.UpdateOpts{}
	var unboundSNI []string
	if slot == SlotDefault {
		listenerUpdateOpts.DefaultTlsContainerRef = &newCert.ID
	} else {
		var sniRefs []string
		sniRefs, unboundSNI = sniRefsForUpdate(sniEntries, oldCertID, newCert.ID, sniDomains)
		listenerUpdateOpts.SniContainerRefs = &sniRefs
	}

	_, err = listeners.Update(elbClient, listenerID, listenerUpdateOpts).Extract()
	if err != nil {
		log.Printf("Error binding to listener %s: %v", listenerID, err)
		// fallback: if bind fails, we directly try to cleanup the new certificate
		certificates.Delete(elbClient, newCert.ID)
		return
	}

	log.Printf("Certificate from %s successfully bound to listener %s (%s slot)!", cacheKey, listenerID, slot)
	for _, id := range unboundSNI {
		log.Printf("SNI certificate %s shared a domain with %s and was unbound from listener %s (not deleted).", id, cacheKey, listenerID)
	}

	// --- 3. WRITE STATE BACK TO KUBERNETES SECRET (Persistent Memory) ---
	patchData, err := syncedAnnotationsPatch(currentState, newCert.ID)
	if err == nil {
		_, err = k8sClient.CoreV1().Secrets(secret.Namespace).Patch(context.TODO(), secret.Name, types.MergePatchType, patchData, metav1.PatchOptions{})
	}
	if err != nil {
		log.Printf("Warning: Could not write sync state annotation to secret %s: %v", cacheKey, err)
	} else {
		log.Printf("Sync state successfully saved to K8s secret %s.", cacheKey)
	}

	// 4. cleanup OLD certificate (asynchron)
	if oldCertID != "" && oldCertID != newCert.ID {
		log.Printf("Starting Cleanup for old certificate: %s", oldCertID)

		// start cleanup within a go routine in the background,
		// so that the controller does not get stuck.
		go func(certToDelete string, client *golangsdk.ServiceClient) {
			// Short pause, since load balancers operate asynchronously.
			// If the certificate is deleted too quickly, T Cloud throws a "Resource in use" error.
			time.Sleep(5 * time.Second)

			oldCert, err := certificates.Get(client, certToDelete).Extract()
			if !shouldDeleteOldCertificate(oldCert, err, keepCertRegex) {
				if err != nil || oldCert == nil {
					log.Printf("Cleanup-warning: Unable to check old certificate %s against keep-pattern; skipping deletion: %v", certToDelete, err)
				} else {
					log.Printf("Cleanup: Certificate %s (name %q) matches %s pattern, skipping deletion.", certToDelete, oldCert.Name, EnvKeepCertRegex)
				}
				return
			}

			err = certificates.Delete(client, certToDelete).ExtractErr()
			if err != nil {
				log.Printf("Cleanup-error: Unable to delete the old certificate %s from T Cloud Public: %v", certToDelete, err)
			} else {
				log.Printf("Cleanup: Old certificate %s successfully deleted!", certToDelete)
			}
		}(oldCertID, elbClient)
	}

	// 5. save current state in cache
	certHashes.Store(cacheKey, currentState)
}
