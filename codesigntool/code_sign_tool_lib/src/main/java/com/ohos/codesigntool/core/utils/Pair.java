/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.ohos.codesigntool.core.utils;

/**
 * Pair of two elements.
 *
 * @since 2023/06/05
 */
public final class Pair<Key, Value> {
    private final Key mKey;

    private final Value mValue;

    private Pair(Key key, Value value) {
        mKey = key;
        mValue = value;
    }

    /**
     * create a pair with key and value
     *
     * @param key key of pair
     * @param value value of pair
     * @param <Key> type of key
     * @param <Value> type of value
     * @return a pair with key and value
     */
    public static <Key, Value> Pair<Key, Value> create(Key key, Value value) {
        return new Pair<Key, Value>(key, value);
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = hashCode(prime, result, mKey);
        return hashCode(prime, result, mValue);
    }

    private <T> int hashCode(int prime, int result, T value) {
        return prime * result + ((value == null) ? 0 : value.hashCode());
    }

    /**
     * get value of pair
     *
     * @return value of pair
     */
    public Value getValue() {
        return mValue;
    }

    /**
     * get key of pair
     *
     * @return key of pair
     */
    public Key getKey() {
        return mKey;
    }

    private <T> boolean compare(T o1, T o2) {
        if (o1 == null) {
            return o2 == null;
        }
        return o1.equals(o2);
    }

    @Override
    public boolean equals(Object object) {
        if (this == object) {
            return true;
        }
        if (object == null) {
            return false;
        }
        if (!(object instanceof Pair)) {
            return false;
        }
        Pair<?, ?> pair = (Pair<?, ?>) object;
        return compare(mKey, pair.getKey()) && compare(mValue, pair.getValue());
    }
}
