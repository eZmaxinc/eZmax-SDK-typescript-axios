/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.17
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



import { DefaultObject } from '../base'

/**
 * Gives informations about the user that created the object or the last user to have modified it.  If the object was never modified after creation, both Created and Modified informations will be the same. 
 * @export
 * @interface CommonAuditdetail
 */
export interface CommonAuditdetail {
    /**
     * The unique ID of the User
     * @type {number}
     * @memberof CommonAuditdetail
     */
    'fkiUserID': number;
    /**
     * The unique ID of the Apikey
     * @type {number}
     * @memberof CommonAuditdetail
     */
    'fkiApikeyID'?: number;
    /**
     * The Login name of the User.
     * @type {string}
     * @memberof CommonAuditdetail
     */
    'sUserLoginname': string;
    /**
     * The Last name of the user
     * @type {string}
     * @memberof CommonAuditdetail
     */
    'sUserLastname': string;
    /**
     * The First name of the user
     * @type {string}
     * @memberof CommonAuditdetail
     */
    'sUserFirstname': string;
    /**
     * The description of the Apikey in the language of the requester
     * @type {string}
     * @memberof CommonAuditdetail
     */
    'sApikeyDescriptionX'?: string;
    /**
     * Represent a Date Time. The timezone is the one configured in the User\'s profile.
     * @type {string}
     * @memberof CommonAuditdetail
     */
    'dtAuditdetailDate': string;
}
/**
 * A CommonAuditdetail Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectCommonAuditdetail
 */
export class DefaultObjectCommonAuditdetail extends DefaultObject {
   fkiUserID:number = 0
   fkiApikeyID?:number = undefined
   sUserLoginname:string = ''
   sUserLastname:string = ''
   sUserFirstname:string = ''
   sApikeyDescriptionX?:string = undefined
   dtAuditdetailDate:string = ''
}


