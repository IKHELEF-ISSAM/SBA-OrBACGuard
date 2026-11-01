import java.io.*;
import java.util.*;
import java.util.regex.*;
import orbac.*;

public class OrBacPolicy_Open5GS {

    public static void main(String[] args) throws IOException {
        String filePath = "PCAP_Attack.txt"; // Chemin du fichier d'entrée
        String outputFilePath_1 = "Deregistration_Requests.txt"; // Chemin du fichier de sortie 1
        String outputFilePath_2 = "Docker_requests.txt"; // Chemin du fichier de sortie 2

       
         String outputFilePath_3 = "Registered.txt"; // Chemin du fichier de sortie 1
   
       
        BufferedReader br = new BufferedReader(new FileReader(filePath));
        String line;

        // Map pour éviter doublons UUID → Source NF
        Map<String, String> uniqueEntries = new HashMap<>();

        // Regex pour extraire les colonnes Time, Source, Destination et Info
        String regex = "^\\s*\\d+\\s+(\\S+)\\s+(\\S+)\\s+(\\S+)\\s+\\S+\\s+(.+)$";

        // Regex pour extraire le UUID dans l'URI PUT
        String uuidRegex = "/nnrf-nfm/v1/nf-instances/([0-9a-fA-F-]{36})";

        while ((line = br.readLine()) != null) {

            // Ignorer les lignes d'en-tête et les lignes vides
            if (line.startsWith("No.") || line.trim().isEmpty()) continue;

            // Matcher l'expression régulière
            Matcher m = Pattern.compile(regex).matcher(line);

            // Si la ligne correspond au format attendu
            if (m.find()) {
                String source = m.group(2);  // Source
                String info = m.group(4);    // Info (contenant le PUT et l'UUID)

                // Filtrer uniquement les lignes contenant un PUT
                if (!info.contains("PUT")) continue;

                // Vérifier que l'UUID est présent dans l'info
                Matcher u = Pattern.compile(uuidRegex).matcher(info);
                if (!u.find()) continue;

                // Extraire l'UUID
                String uuid = u.group(1);

                // Filtrer pour ne pas inclure les lignes où la source est SCP
                if (!source.equals("SCP")) {
                    // Ajouter l'entrée unique (UUID, Source)
                    uniqueEntries.put(uuid, source);
                }
            }
        }

        br.close();

        // Écrire les résultats dans le fichier de sortie
        BufferedWriter writer = new BufferedWriter(new FileWriter(outputFilePath_3));
        for (Map.Entry<String, String> entry : uniqueEntries.entrySet()) {
            // Écrire les lignes avec Source, Registered, et UUID
            writer.write(mapDockerNumber(entry.getValue()) + "\tRegistered\t" + entry.getKey());
            writer.newLine();
        }

        writer.close();

        System.out.println("Registered Functions File Generated : " + outputFilePath_3);
   



        Pattern deletePattern = Pattern.compile("DELETE /nnrf-nfm/v1/nf-instances/([0-9a-fA-F-]{36})");

        Pattern getRequestPattern = Pattern.compile("GET\\s+([\\S]+)"); // Capture l'URL après "GET"
     
        // Traitement des requêtes Deregistration (DELETE)
        extractDeregistrationRequests(filePath, outputFilePath_1, deletePattern);

        // Traitement des requêtes Docker
        List<String> extractedData = processDockerRequests(filePath, getRequestPattern);
        writeDockerRequestsToFile(outputFilePath_2, extractedData);

        // Gestion des politiques Orbac
        handleOrbacPolicy("5g", outputFilePath_1,outputFilePath_2);
    }

    // Traiter les requêtes DELETE et extraire les nfID
    public static void extractDeregistrationRequests(String filePath, String outputFilePath, Pattern deletePattern) throws IOException {
        // Map pour associer chaque source à un Docker spécifique
        try (BufferedReader br = new BufferedReader(new FileReader(filePath));
             BufferedWriter writer = new BufferedWriter(new FileWriter(outputFilePath))) {
writer.write("Docker2" + " " + "fc093e02-ced5-41f0-a892-03a0866e1b79");
   writer.newLine();
writer.write("Docker3" + " " + "fc093e02-ced5-41f0-a892-03a0866e1b79");
   writer.newLine();
            String line;
            while ((line = br.readLine()) != null) {
                if (line.trim().isEmpty() || line.startsWith("No.")) continue;

                // Chercher les requêtes DELETE dans la ligne
                Matcher deleteMatcher = deletePattern.matcher(line);
                                           
                if (deleteMatcher.find()) {
                    String nfID = deleteMatcher.group(1);  // Extraire le nfID
                    String source = extractSource(line);  // Extraire la source de la requête

                    // Vérification que la source est différente de "SCP" et extraction du Docker
                    if (source != null && !source.equals("SCP")) {
                        String docker = mapDockerNumber(source);  // Utilisation de mapDockerNumber()
                        if (!docker.isEmpty()) {
                            // Écrire le Docker et le nfID dans le fichier de sortie
                            writer.write(docker + " " + nfID);
                            writer.newLine();
                        }

                    }
                }
            }
        }
        System.out.println("Deregistration requests were saved in : " + outputFilePath);
    }




    // Traiter les requêtes Docker dans le fichier d'entrée
    private static List<String> processDockerRequests(String filePath, Pattern getRequestPattern) throws IOException {
        List<String> extractedData = new ArrayList<>();
        try (BufferedReader br = new BufferedReader(new FileReader(filePath))) {
            String line;
            while ((line = br.readLine()) != null) {
                if (line.startsWith("No.") || line.trim().isEmpty()) continue;
                Matcher matcher = getRequestPattern.matcher(line);
                if (matcher.find()) {
                    String url = matcher.group(1);
                    String requesterNfType = getRequestParamValue(url, "requester-nf-type");
                    String targetNfType = getRequestParamValue(url, "target-nf-type");
                    String serviceName = getRequestParamValue(url, "service-names");

                    String requestType = mapRequestType(serviceName);
                    String dockerNumberSource = mapDockerNumber(requesterNfType);
                    String dockerNumberTarget = mapDockerNumber(targetNfType);

                    if (!dockerNumberSource.isEmpty() && !dockerNumberTarget.isEmpty()) {
                        extractedData.add(dockerNumberSource + " " + requestType + " " + dockerNumberTarget);
                    }
                }
            }
        }
        return extractedData;
    }

    // Écrire les requêtes Docker dans le fichier de sortie
    private static void writeDockerRequestsToFile(String outputFilePath, List<String> extractedData) throws IOException {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(outputFilePath))) {
            for (String data : extractedData) {
                writer.write(data);
                writer.newLine();
            }
            writer.write("Docker7 Request_1 Docker11");
            writer.newLine();
            writer.write("Docker14 Request_1 Docker11");
            writer.newLine();
            writer.write("Docker7 Request_7 Docker11");
            writer.newLine();
         
        }
        System.out.println("The Discovery requests were saved in : " + outputFilePath);
    }

    private static void handleOrbacPolicy(String pathToPolicy, String deregistrationFile, String dockerRequestFile) {
    try {
        // Initialisation du moteur OrBAC
        COrbacCore core = COrbacCore.GetTheInstance();
        AbstractOrbacPolicy policy = core.LoadPolicy(pathToPolicy);

        // Lecture et traitement du fichier Deregistration Requests
        try (BufferedReader reader = new BufferedReader(new FileReader(deregistrationFile))) {
            String lineRequest;
            while ((lineRequest = reader.readLine()) != null) {
                String[] parts = lineRequest.split(" ");
                if (parts.length == 2) {
                    String subject = parts[0];  // Docker number from Deregistration request
                    String action = "Request_5";
                    String object = "Docker11";  

                    // Vérification de la politique OrBAC
                    boolean isProhibited = policy.IsProhibited(subject, action, object);
                    boolean isPermitted = policy.IsPermited(subject, action, object);

                    if (isProhibited) {
                        System.out.println(subject + " is NOT permitted to execute deregistration  " + action + " on " + object + " (Prohibited)");
                    } else if (isPermitted) {
                        System.out.println(subject + " is permitted to execute deregistration " + action + " on " + object + " (Permitted)");
                    } else {
                        System.out.println(subject + " is NOT permitted to execute deregistration " + action + " on " + object + " (No rule defined)");
                    }
                }
            }
        }

        // Lecture et traitement des requêtes Docker (à partir du fichier Docker_requests.txt)
        try (BufferedReader reader = new BufferedReader(new FileReader(dockerRequestFile))) {
            String lineRequest;
            while ((lineRequest = reader.readLine()) != null) {
                String[] parts = lineRequest.split(" ");
                if (parts.length == 3) {
                    String subject = parts[0];  // Docker number from Docker request
                    String action = parts[1];   // Request type (e.g., Request_1, Request_7, etc.)
                    String object = "Docker11";  

                    // Vérification de la politique OrBAC pour les requêtes Docker
                    boolean isProhibited = policy.IsProhibited(subject, action, object);
                    boolean isPermitted = policy.IsPermited(subject, action, object);

                    if (isProhibited) {
                        System.out.println(subject + " is NOT permitted to execute Discovery " + action + " on " + object + " (Prohibited)");
                    } else if (isPermitted) {
                        System.out.println(subject + " is permitted to execute Discovery " + action + " on " + object + " (Permitted)");
                    } else {
                        System.out.println(subject + " is NOT permitted to execute Discovery " + action + " on " + object + " (No rule defined)");
                    }
                }
            }
        }

    } catch (IOException e) {
        System.out.println("File read error: " + e.getMessage());
    } catch (Exception e) {
        System.out.println("Error: " + e.getMessage());
        e.printStackTrace();
    }
}

    // Fonction pour récupérer les valeurs des paramètres dans l'URL
    public static String getRequestParamValue(String url, String paramName) {
        Pattern pattern = Pattern.compile(paramName + "=([^&]+)");
        Matcher matcher = pattern.matcher(url);
        return matcher.find() ? matcher.group(1) : "";
    }

      // Fonction pour mapper le service name à un Request Type
    public static String mapRequestType(String serviceName) {
        Map<String, String> serviceToRequestType = new HashMap<>();
        serviceToRequestType.put("namf-comm", "Request_6_Namf_Communication");
        serviceToRequestType.put("Namf_MT", "Request_6_Namf_MT");
        serviceToRequestType.put("Namf_Location", "Request_6_Namf_Location");
        serviceToRequestType.put("Namf_EventExposure", "Request_6_Namf_EventExposure");
        serviceToRequestType.put("Nsmf_PDUSession", "Request_6_Nsmf_PDUSession");
        serviceToRequestType.put("Nsmf_EventExposure", "Request_6_Nsmf_EventExposure");
        serviceToRequestType.put("Nausf_SoRProtection", "Request_6_Nausf_SoRProtection");
        serviceToRequestType.put("Nausf_UPUProtection", "Request_6_Nausf_UPUProtection");
        serviceToRequestType.put("nausf-auth", "Request_6_Nausf_UEAuthentication");
        serviceToRequestType.put("nudm-uecm", "Request_6_Nudm_UECM");
        serviceToRequestType.put("nudm-sdm", "Request_6_Nudm_SDM");
        serviceToRequestType.put("nudm-ueau", "Request_6_Nudm_UEAuthentication");
        serviceToRequestType.put("Nudm_EventExposure", "Request_6_Nudm_EventExposure");
        serviceToRequestType.put("Nudm_ParameterProvision", "Request_6_Nudm_ParameterProvision");
        serviceToRequestType.put("Npcf_SMPolicyControl", "Request_6_Npcf_SMPolicyControl");
        serviceToRequestType.put("Npcf_PolicyAuthorization", "Request_6_Npcf_PolicyAuthorization");
        serviceToRequestType.put("Npcf_AMPolicyControl", "Request_6_Npcf_AMPolicyControl");
        serviceToRequestType.put("Npcf_BDTPolicyControl", "Request_6_Npcf_BDTPolicyControl");
        serviceToRequestType.put("Npcf_UEPolicyControl", "Request_6_Npcf_UEPolicyControl");
        serviceToRequestType.put("Npcf_EventExposure", "Request_6_Npcf_EventExposure");
        serviceToRequestType.put("Nnef_EventExposure", "Request_6_Nnef_EventExposure");
        serviceToRequestType.put("Nnef_PFDManagement", "Request_6_Nnef_PFDManagement");
        serviceToRequestType.put("Nnef_ParameterProvision", "Request_6_Nnef_ParameterProvision");
        serviceToRequestType.put("Nnef_Trigger", "Request_6_Nnef_Trigger");
        serviceToRequestType.put("Nnef_BDTPNegotiation", "Request_6_Nnef_BDTPNegotiation");
        serviceToRequestType.put("Nnef_TrafficInfluence", "Request_6_Nnef_TrafficInfluence");
        serviceToRequestType.put("Nnef_ChargeableParty", "Request_6_Nnef_ChargeableParty");
        serviceToRequestType.put("Nnef_AFsessionWithQoS", "Request_6_Nnef_AFsessionWithQoS");
        serviceToRequestType.put("nudr-dr", "Request_6_Nudr_DataManagement");
        serviceToRequestType.put("Nnssf_NSSelection", "Request_6_Nnssf_NSSelection");
        serviceToRequestType.put("Nnssf_NSSAIAvailability", "Request_6_Nnssf_NSSAIAvailability");
        serviceToRequestType.put("nbsf-management", "Request_6_Nbsf_Bootstrap_Management");
        serviceToRequestType.put("Nbsf_Binding", "Request_6_Nbsf_Binding");
        serviceToRequestType.put("Nbsf_Key_Provisioning", "Request_6_Nbsf_Key_Provisioning");
        serviceToRequestType.put("Naf_SessionWithQoS", "Request_6_Naf_SessionWithQoS");
        serviceToRequestType.put("Naf_EventExposure", "Request_6_Naf_EventExposure");
        serviceToRequestType.put("Naf_UEPolicyProvision", "Request_6_Naf_UEPolicyProvision");
        serviceToRequestType.put("Naf_TrafficInfluence", "Request_6_Naf_TrafficInfluence");
        serviceToRequestType.put("Naf_Charging", "Request_6_Naf_Charging");
        serviceToRequestType.put("Nnwdaf_EventsSubscription", "Request_6_Nnwdaf_EventsSubscription");
        serviceToRequestType.put("Nnwdaf_AnalyticsInfo", "Request_6_Nnwdaf_AnalyticsInfo");

        return serviceToRequestType.getOrDefault(serviceName, "");
    }


    // Fonction pour mapper requester-nf-type ou target-nf-type à un numéro Docker
    public static String mapDockerNumber(String nfType) {
        Map<String, String> nfTypeToDocker = new HashMap<>();
        nfTypeToDocker.put("SCP", "Docker1");
        nfTypeToDocker.put("PCF", "Docker2");
        nfTypeToDocker.put("NWDAF", "Docker3");
        nfTypeToDocker.put("BSF", "Docker4");
        nfTypeToDocker.put("UDM", "Docker5");
        nfTypeToDocker.put("AUSF", "Docker6");
        nfTypeToDocker.put("AMF", "Docker7");
        nfTypeToDocker.put("NSSF", "Docker8");
        nfTypeToDocker.put("GMLC", "Docker9");
        nfTypeToDocker.put("UDR", "Docker10");
        nfTypeToDocker.put("NRF", "Docker11");
        nfTypeToDocker.put("LMF", "Docker12");
        nfTypeToDocker.put("AF", "Docker13");
        nfTypeToDocker.put("UPF", "Docker14");
        nfTypeToDocker.put("NSSAAF", "Docker15");
        nfTypeToDocker.put("SMSF", "Docker16");
        nfTypeToDocker.put("SMF", "Docker17");
        nfTypeToDocker.put("NEF", "Docker18");
        nfTypeToDocker.put("NSACF", "Docker19");
        nfTypeToDocker.put("EASDF", "Docker20");
       
        return nfTypeToDocker.getOrDefault(nfType, "");
    }

    // Fonction pour extraire la source d'une ligne (supposée dans la 3ème colonne)
    public static String extractSource(String line) {
        String[] parts = line.split("\\s+"); // Sépare les colonnes par des espaces
        if (parts.length > 3) {
            return parts[3];  // La source se trouve dans la 3ème colonne (index 2)
        }
        return null;
    }
}
