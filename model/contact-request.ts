/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.11
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



import { DefaultObject } from '../base'

/**
 * A Contact Object
 * @export
 * @interface ContactRequest
 */
export interface ContactRequest {
    /**
     * The unique ID of the Contacttitle.  Valid values:  |Value|Description| |-|-| |1|Ms.| |2|Mr.| |4|(Blank)| |5|Me (For Notaries)|
     * @type {number}
     * @memberof ContactRequest
     */
    'fkiContacttitleID': number;
    /**
     * The unique ID of the Language.  Valid values:  |Value|Description| |-|-| |1|French| |2|English|
     * @type {number}
     * @memberof ContactRequest
     */
    'fkiLanguageID': number;
    /**
     * The First name of the contact
     * @type {string}
     * @memberof ContactRequest
     */
    'sContactFirstname': string;
    /**
     * The Last name of the contact
     * @type {string}
     * @memberof ContactRequest
     */
    'sContactLastname': string;
    /**
     * The Company name of the contact
     * @type {string}
     * @memberof ContactRequest
     */
    'sContactCompany': string;
    /**
     * The Birth Date of the contact
     * @type {string}
     * @memberof ContactRequest
     */
    'dtContactBirthdate'?: string;
}
/**
 * A ContactRequest Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectContactRequest
 */
export class DefaultObjectContactRequest extends DefaultObject {
   fkiContacttitleID:number = 0
   fkiLanguageID:number = 0
   sContactFirstname:string = ''
   sContactLastname:string = ''
   sContactCompany:string = ''
   dtContactBirthdate?:string = undefined
}


