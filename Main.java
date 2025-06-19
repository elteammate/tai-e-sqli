public class Main {
    public void sink(String s) {}

    public void entry1(String x) {
        sink(x + "a");
    }

    public void entry2(String x) {
        sink(x + "b");
    }
}