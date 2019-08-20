package sombrero.common;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;
import sombrero.account.Account;
import sombrero.account.AccountService;
import sombrero.book.Book;
import sombrero.book.BookRepository;

@Component
public class DefaultDataGenerator implements ApplicationRunner {

    @Autowired
    AccountService accountService;

    @Autowired
    BookRepository bookRepository;

    @Override
    public void run(ApplicationArguments args) throws Exception {
        /**
         * 사용자(2명) -> 책이름
         * -----------------
         * anton -> oyster
         * gogol -> overcoat
         * -----------------
         */
        Account anton = createUser("anton");
        Account gogol = createUser("gogol");
        createBook("oyster", anton);
        createBook("overcoat", gogol);
    }

    private void createBook(String title, Account account) {
        Book book = new Book();
        book.setTitle(title);
        book.setAuthor(account);
        bookRepository.save(book);
    }

    private Account createUser(String username) {
        Account account = new Account();
        account.setUsername(username);
        account.setPassword("123");
        account.setRole("USER");
        return accountService.createNew(account);
    }

}
