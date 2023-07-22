/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.18
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



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
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A ContactRequest Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectContactRequest
 */
export class DataObjectContactRequest {
   fkiContacttitleID:number = 0
   fkiLanguageID:number = 0
   sContactFirstname:string = ''
   sContactLastname:string = ''
   sContactCompany:string = ''
   dtContactBirthdate?:string = undefined
}

/**
 * @export 
 * A ContactRequest Validation Object
 * @class ValidationObjectContactRequest
 */
export class ValidationObjectContactRequest {
   fkiContacttitleID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   fkiLanguageID = {
      type: 'integer',
      minimum: 1,
      maximum: 2,
      required: true
   }
   sContactFirstname = {
      type: 'string',
      required: true
   }
   sContactLastname = {
      type: 'string',
      required: true
   }
   sContactCompany = {
      type: 'string',
      required: true
   }
   dtContactBirthdate = {
      type: 'string',
      required: false
   }
} 


