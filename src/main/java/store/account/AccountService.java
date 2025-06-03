package store.account;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.stream.StreamSupport;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

@Service
public class AccountService {

    @Autowired
    private AccountRepository accountRepository;

    @Cacheable(cacheNames = "accounts", key = "#id")
    public Account findById(String id) {
        return accountRepository.findById(id)
            .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Account not found"))
            .to();
    }

    @CacheEvict(cacheNames = "accounts", allEntries = true)
    public Account create(Account account) {
        String pass = account.password().trim();
        if (pass.length() < 8) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Password too short!");
        }
        account.sha256(calcHash(pass));
        account.creation(new Date());
        return accountRepository.save(new AccountModel(account)).to();
    }

    public Account findByEmailAndPassword(String email, String password) {
        String sha256 = calcHash(password);
        AccountModel m = accountRepository.findByEmailAndSha256(email, sha256);
        return m == null ? null : m.to();
    }

    @Cacheable(cacheNames = "accounts", key = "'all'")
    public List<Account> findAll() {
        return StreamSupport.stream(accountRepository.findAll().spliterator(), false)
            .map(AccountModel::to)
            .toList();
    }

    @CacheEvict(cacheNames = "accounts", key = "#id")
    public void deleteById(String id) {
        accountRepository.deleteById(id);
    }

    private String calcHash(String value) {
        try {
            MessageDigest digester = MessageDigest.getInstance("SHA-256");
            byte[] hash = digester.digest(value.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
}