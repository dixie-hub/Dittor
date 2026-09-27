package dittor.crypto;

import org.cryptimeleon.math.structures.groups.GroupElement;
import org.cryptimeleon.math.structures.groups.elliptic.BilinearGroup;
import org.cryptimeleon.mclwrap.bn254.MclBilinearGroup;
import org.cryptimeleon.mclwrap.bn254.MclBilinearGroup.GroupChoice;

// Inicialização centralizada do grupo bilinear (BLS12-381) e dos geradores usados
// pelo Pedersen Commitment (g1, h1) e pelas assinaturas (g2). Main.java e CAMain.java
// têm de derivar exatamente os mesmos valores para as CAs e os Users interagirem
// corretamente — usar esta classe em ambos evita que um dos dois fique dessincronizado
// se a curva ou a semente do h1 mudar no futuro.
public final class CryptimeleonSetup {

    public static final String PEDERSEN_H1_SEED = "Dittor-Pedersen-h1-2026";

    private final BilinearGroup pairing;
    private final GroupElement g1;
    private final GroupElement h1;
    private final GroupElement g2;

    public CryptimeleonSetup() {
        this.pairing = new MclBilinearGroup(GroupChoice.BLS12_381); // 128 bits de segurança
        this.g1 = pairing.getG1().getGenerator();
        this.h1 = pairing.getHashIntoG1().hash(PEDERSEN_H1_SEED); // gerador independente, fixo
        this.g2 = pairing.getG2().getGenerator();
    }

    public BilinearGroup getPairing() {
        return pairing;
    }

    public GroupElement getG1() {
        return g1;
    }

    public GroupElement getH1() {
        return h1;
    }

    public GroupElement getG2() {
        return g2;
    }
}
