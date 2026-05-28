package dittor.crypto.vrf;

import org.cryptimeleon.math.structures.groups.GroupElement;

public class VRFResult {
    public final GroupElement nym;
    public final GroupElement zkp;

    public VRFResult(GroupElement y, GroupElement pi) {
        this.nym = y;
        this.zkp = pi;
    }

    public GroupElement getPseudonym() {
        return this.nym;
    }

    public GroupElement getZeroKnowledgeProof() {
        return this.zkp;
    }
}
