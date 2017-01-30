package de.wuthoehle.argon2jni;
/*
 * Copyright (c) Marco Huenseler
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

public final class SecurityParameters {
    public int t_cost, m_cost, parallelism;

    public SecurityParameters(int t_cost, int m_cost, int parallelism) {
        this.t_cost = t_cost;
        this.m_cost = m_cost;
        this.parallelism = parallelism;
    }
}
