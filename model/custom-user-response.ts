/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.8
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



/**
 * A User Object
 * @export
 * @interface CustomUserResponse
 */
export interface CustomUserResponse {
    /**
     * The unique ID of the User
     * @type {number}
     * @memberof CustomUserResponse
     */
    'pkiUserID': number;
    /**
     * The Last name of the user
     * @type {string}
     * @memberof CustomUserResponse
     */
    'sUserLastname': string;
    /**
     * The First name of the user
     * @type {string}
     * @memberof CustomUserResponse
     */
    'sUserFirstname': string;
    /**
     * The email address.
     * @type {string}
     * @memberof CustomUserResponse
     */
    'sEmailAddress': string;
}

