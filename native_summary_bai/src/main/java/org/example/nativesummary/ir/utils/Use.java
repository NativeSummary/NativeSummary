package org.example.nativesummary.ir.utils;

import java.io.Serializable;

// Use relationship from user to value
public class Use implements Serializable {
    public User user;
    public Value value;

    public Use(User user, Value value) {
        this.user = user;
        this.value = value;
        this.value.addUse(this);
    }
}
