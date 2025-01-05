package cu.entalla.security.authentication;

import org.springframework.data.domain.Example;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.repository.query.FluentQuery;

import java.util.List;
import java.util.Optional;
import java.util.function.Function;

public class UserRepositoryImpl implements UserRepository{


    @Override
    public CustomUserDetails findByUsername(String username) {
        return null;
    }


    @Override
    public void flush() {

    }

    @Override
    public <S extends CustomUserDetails> S saveAndFlush(S entity) {
        return null;
    }

    @Override
    public <S extends CustomUserDetails> List<S> saveAllAndFlush(Iterable<S> entities) {
        return null;
    }

    @Override
    public void deleteInBatch(Iterable<CustomUserDetails> entities) {
        UserRepository.super.deleteInBatch(entities);
    }

    @Override
    public void deleteAllInBatch(Iterable<CustomUserDetails> entities) {

    }

    @Override
    public void deleteAllByIdInBatch(Iterable<Long> longs) {

    }

    @Override
    public void deleteAllInBatch() {

    }

    @Override
    public CustomUserDetails getOne(Long aLong) {
        return null;
    }

    @Override
    public CustomUserDetails getById(Long aLong) {
        return null;
    }

    @Override
    public CustomUserDetails getReferenceById(Long aLong) {
        return null;
    }

    @Override
    public <S extends CustomUserDetails> Optional<S> findOne(Example<S> example) {
        return Optional.empty();
    }

    @Override
    public <S extends CustomUserDetails> List<S> findAll(org.springframework.data.domain.Example<S> example) {
        return null;
    }

    @Override
    public <S extends CustomUserDetails> List<S> findAll(org.springframework.data.domain.Example<S> example, org.springframework.data.domain.Sort sort) {
        return null;
    }

    @Override
    public <S extends CustomUserDetails> Page<S> findAll(Example<S> example, Pageable pageable) {
        return null;
    }

    @Override
    public <S extends CustomUserDetails> long count(Example<S> example) {
        return 0;
    }

    @Override
    public <S extends CustomUserDetails> boolean exists(Example<S> example) {
        return false;
    }

    @Override
    public <S extends CustomUserDetails, R> R findBy(Example<S> example, Function<FluentQuery.FetchableFluentQuery<S>, R> queryFunction) {
        return null;
    }

    @Override
    public <S extends CustomUserDetails> S save(S entity) {
        return null;
    }

    @Override
    public <S extends CustomUserDetails> List<S> saveAll(Iterable<S> entities) {
        return null;
    }

    @Override
    public Optional<CustomUserDetails> findById(Long aLong) {
        return Optional.empty();
    }

    @Override
    public boolean existsById(Long aLong) {
        return false;
    }

    @Override
    public List<CustomUserDetails> findAll() {
        return null;
    }

    @Override
    public List<CustomUserDetails> findAllById(Iterable<Long> longs) {
        return null;
    }

    @Override
    public long count() {
        return 0;
    }

    @Override
    public void deleteById(Long aLong) {

    }

    @Override
    public void delete(CustomUserDetails entity) {

    }

    @Override
    public void deleteAllById(Iterable<? extends Long> longs) {

    }

    @Override
    public void deleteAll(Iterable<? extends CustomUserDetails> entities) {

    }

    @Override
    public void deleteAll() {

    }

    @Override
    public List<CustomUserDetails> findAll(Sort sort) {
        return null;
    }

    @Override
    public Page<CustomUserDetails> findAll(Pageable pageable) {
        return null;
    }
}
