//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.config.forms;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

class FieldVisibilityManager {
    private static Log logger = LogFactory.getLog(FieldVisibilityManager.class);
    private List<FieldVisibilityInstruction> visibilityInstructions = new ArrayList();

    FieldVisibilityManager() {
    }

    void addInstruction(String showOrHide, String fieldId, String modesString) {
        this.visibilityInstructions.add(new FieldVisibilityInstruction(showOrHide, fieldId, modesString));
    }

    public FieldVisibilityManager combine(FieldVisibilityManager otherFVM) {
        if (otherFVM == this) {
            return this;
        } else {
            FieldVisibilityManager result = new FieldVisibilityManager();
            result.visibilityInstructions.addAll(this.visibilityInstructions);
            result.visibilityInstructions.addAll(otherFVM.visibilityInstructions);
            return result;
        }
    }

    public boolean isFieldVisible(String fieldId, Mode m) {
        if (this.visibilityInstructions.isEmpty()) {
            return true;
        } else {
            int indexOfFirstShow = this.getIndexOfFirstShow();
            if (indexOfFirstShow != -1) {
                List<FieldVisibilityInstruction> relevantInstructions = this.visibilityInstructions.subList(indexOfFirstShow, this.visibilityInstructions.size());
                boolean showCurrentField = false;
                Iterator var6 = relevantInstructions.iterator();

                while(var6.hasNext()) {
                    FieldVisibilityInstruction fvi = (FieldVisibilityInstruction)var6.next();
                    if (fvi.getFieldId().equals(fieldId) && fvi.getModes().contains(m)) {
                        showCurrentField = fvi.getShowOrHide().equals(Visibility.SHOW);
                    }
                }

                return showCurrentField;
            } else {
                Iterator var4 = this.visibilityInstructions.iterator();

                FieldVisibilityInstruction fvi;
                do {
                    if (!var4.hasNext()) {
                        return true;
                    }

                    fvi = (FieldVisibilityInstruction)var4.next();
                } while(!fvi.getFieldId().equals(fieldId) || !fvi.getShowOrHide().equals(Visibility.HIDE) || !fvi.getModes().contains(m));

                return false;
            }
        }
    }

    public boolean isFieldHidden(String fieldId, Mode m) {
        Iterator var3 = this.visibilityInstructions.iterator();

        FieldVisibilityInstruction fvi;
        do {
            if (!var3.hasNext()) {
                return false;
            }

            fvi = (FieldVisibilityInstruction)var3.next();
        } while(!fvi.getFieldId().equals(fieldId) || !fvi.getShowOrHide().equals(Visibility.HIDE) || !fvi.getModes().contains(m));

        return true;
    }

    public int getIndexOfFirstShow() {
        for(int i = 0; i < this.visibilityInstructions.size(); ++i) {
            if (((FieldVisibilityInstruction)this.visibilityInstructions.get(i)).getShowOrHide().equals(Visibility.SHOW)) {
                return i;
            }
        }

        return -1;
    }

    public boolean isManagingHiddenFields() {
        return this.getIndexOfFirstShow() != -1;
    }

    public List<String> getFieldNamesVisibleInMode(Mode mode) {
        int indexOfFirstShow = this.getIndexOfFirstShow();
        if (indexOfFirstShow == -1) {
            return null;
        } else {
            Set<String> result = new LinkedHashSet();
            List<FieldVisibilityInstruction> relevantInstructions = this.visibilityInstructions.subList(indexOfFirstShow, this.visibilityInstructions.size());
            Iterator var5 = relevantInstructions.iterator();

            while(var5.hasNext()) {
                FieldVisibilityInstruction fvi = (FieldVisibilityInstruction)var5.next();
                if (fvi.getModes().contains(mode)) {
                    if (fvi.getShowOrHide().equals(Visibility.SHOW)) {
                        result.add(fvi.getFieldId());
                    } else if (fvi.getShowOrHide().equals(Visibility.HIDE)) {
                        result.remove(fvi.getFieldId());
                    }
                }
            }

            return Collections.unmodifiableList(new ArrayList(result));
        }
    }

    public List<String> getFieldNamesHiddenInMode(Mode mode) {
        int indexOfFirstShow = this.getIndexOfFirstShow();
        if (indexOfFirstShow != -1) {
            return null;
        } else {
            Set<String> result = new LinkedHashSet();
            Iterator var4 = this.visibilityInstructions.iterator();

            while(var4.hasNext()) {
                FieldVisibilityInstruction fvi = (FieldVisibilityInstruction)var4.next();
                if (fvi.getModes().contains(mode) && fvi.getShowOrHide().equals(Visibility.HIDE)) {
                    result.add(fvi.getFieldId());
                }
            }

            if (result.size() == 0) {
                return null;
            } else {
                return Collections.unmodifiableList(new ArrayList(result));
            }
        }
    }
}
