package sombrero.test;

/**
 * 템플릿 메소드 패턴
 */
public class Child extends Parent {

    @Override
    public void method_abstract() {
        System.out.println("im child..");
    }

    public static void main(String[] args) {
        Parent child = new Child();
        child.method_parent();
    }
}
