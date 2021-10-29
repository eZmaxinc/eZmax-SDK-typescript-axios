/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.3
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


import { CommonAudit } from './common-audit';
import { FieldEUserType } from './field-euser-type';

/**
 * A User Object
 * @export
 * @interface UserResponse
 */
export interface UserResponse {
    /**
     * The unique ID of the User
     * @type {number}
     * @memberof UserResponse
     */
    'pkiUserID': number;
    /**
     * The unique ID of the Language.  Valid values:  |Value|Description| |-|-| |1|French| |2|English|
     * @type {number}
     * @memberof UserResponse
     */
    'fkiLanguageID': number;
    /**
     * 
     * @type {FieldEUserType}
     * @memberof UserResponse
     */
    'eUserType': FieldEUserType;
    /**
     * The First name of the user
     * @type {string}
     * @memberof UserResponse
     */
    'sUserFirstname': string;
    /**
     * The Last name of the user
     * @type {string}
     * @memberof UserResponse
     */
    'sUserLastname': string;
    /**
     * The Login name of the User.
     * @type {string}
     * @memberof UserResponse
     */
    'sUserLoginname': string;
    /**
     * 
     * @type {CommonAudit}
     * @memberof UserResponse
     */
    'objAudit': CommonAudit;
}

