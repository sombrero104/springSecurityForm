package sombrero.test;

/**
 * 템플릿 메소드 패턴
 */
public abstract class Parent {

    public abstract void method_abstract();

    public void method_parent() {
        System.out.println("im parent..");
        this.method_abstract();
    }

}
