# Artifact limitations and integrity notes

- No Open5GS deployment scripts or Docker Compose configuration were present in the supplied archive.
- No `orbac` package or JAR was supplied.
- The Java program references `PCAP_Attack.txt`, which was not supplied.
- The original Java filename differs from its public class name; the source is preserved, and the compilation workaround is documented.
- The Java code contains environment-specific assumptions and hard-coded identifiers. Review these before generalizing results.
- Sample intermediate files and screenshots are not sufficient to establish detection accuracy, overhead or statistical significance.
- No formal license or bibliographic record was included.
- The policy file is preserved as provided, without asserting correctness of its rules.
