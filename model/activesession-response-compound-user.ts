/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.5
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



/**
 * An Activesession->User Object and children to create a complete structure
 * @export
 * @interface ActivesessionResponseCompoundUser
 */
export interface ActivesessionResponseCompoundUser {
    /**
     * The unique ID of the User
     * @type {number}
     * @memberof ActivesessionResponseCompoundUser
     */
    'pkiUserID': number;
    /**
     * The url of the picture used as avatar
     * @type {string}
     * @memberof ActivesessionResponseCompoundUser
     */
    'sAvatarUrl': string;
    /**
     * The First name of the user
     * @type {string}
     * @memberof ActivesessionResponseCompoundUser
     */
    'sUserFirstname': string;
    /**
     * The Last name of the user
     * @type {string}
     * @memberof ActivesessionResponseCompoundUser
     */
    'sUserLastname': string;
    /**
     * The email address.
     * @type {string}
     * @memberof ActivesessionResponseCompoundUser
     */
    'sEmailAddress': string;
}

