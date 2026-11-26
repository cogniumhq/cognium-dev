package app;

import java.util.HashMap;
import java.util.Map;

/** Enum constants with their own bodies, then fields, a constructor and methods. */
public enum Op {
    ADD("+") {
        @Override
        int apply(int a, int b) {
            return a + b;
        }
    },
    SUB("-") {
        @Override
        int apply(int a, int b) {
            return a - b;
        }
    };

    private static final Map<String, Op> BY_SYMBOL = new HashMap<>();

    static {
        for (Op op : values()) {
            BY_SYMBOL.put(op.symbol, op);
        }
    }

    private final String symbol;

    Op(String symbol) {
        this.symbol = symbol;
    }

    abstract int apply(int a, int b);

    public String symbol() {
        return symbol;
    }

    public static Op of(String symbol) {
        Op op = BY_SYMBOL.get(symbol);
        if (op == null) {
            throw new IllegalArgumentException(symbol);
        }
        return op;
    }
}
