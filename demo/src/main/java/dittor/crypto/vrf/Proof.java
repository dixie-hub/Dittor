package dittor.crypto.vrf;

import org.cryptimeleon.math.structures.rings.zn.Zn;

public class Proof {
    public final Zn.ZnElement challenge;
    public final Zn.ZnElement response;

    public Proof(Zn.ZnElement challenge, Zn.ZnElement response) {
        this.challenge = challenge;
        this.response = response;
    }
    
    public Zn.ZnElement getChallenge() {
        return this.challenge;
    }

    public Zn.ZnElement getResponse() {
        return this.response;
    }
}
