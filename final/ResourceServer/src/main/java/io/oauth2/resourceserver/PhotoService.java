package io.oauth2.resourceserver;


import io.oauth2.sharedobject.Photo;

public class PhotoService {

    public static Photo getBuild(String photoId, String photoTitle, String description, String user1) {
        return Photo.builder()
                .photoId(photoId)
                .photoTitle(photoTitle)
                .photoDescription(description)
                .userId(user1)
                .build();
    }

}