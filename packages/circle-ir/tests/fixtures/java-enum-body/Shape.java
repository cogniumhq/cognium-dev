package app;

/** A class with a nested enum whose body declares a field, a constructor and a method. */
public class Shape {
    public enum Kind {
        SQUARE(4), TRIANGLE(3);

        private final int sides;

        Kind(int sides) {
            this.sides = sides;
        }

        public int sides() {
            return sides;
        }
    }

    private final Kind kind;

    public Shape(Kind kind) {
        this.kind = kind;
    }

    public int sides() {
        return kind.sides();
    }
}
