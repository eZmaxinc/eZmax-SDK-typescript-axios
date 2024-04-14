/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.1
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { ContactRequest } from './contact-request';
// May contain unused imports in some cases
// @ts-ignore
import { ContactinformationsRequestCompound } from './contactinformations-request-compound';

/**
 * @type ContactRequestCompound
 * A Contact Object and children to create a complete structure
 * @export
 */
/*export type ContactRequestCompound = ContactRequest;*/
export interface ContactRequestCompound {
    /**
     * The unique ID of the Contacttitle.  Valid values:  |Value|Description| |-|-| |1|Ms.| |2|Mr.| |4|(Blank)| |5|Me (For Notaries)|
     * @type {number}
     * @memberof ContactRequestCompound
     */
    fkiContacttitleID:number 
    /**
     * The unique ID of the Language.  Valid values:  |Value|Description| |-|-| |1|French| |2|English|
     * @type {number}
     * @memberof ContactRequestCompound
     */
    fkiLanguageID:number 
    /**
     * The First name of the contact
     * @type {string}
     * @memberof ContactRequestCompound
     */
    sContactFirstname:string 
    /**
     * The Last name of the contact
     * @type {string}
     * @memberof ContactRequestCompound
     */
    sContactLastname:string 
    /**
     * The Company name of the contact
     * @type {string}
     * @memberof ContactRequestCompound
     */
    sContactCompany:string 
    /**
     * The Birth Date of the contact
     * @type {string}
     * @memberof ContactRequestCompound
     */
    dtContactBirthdate?:string 
    /**
     * 
     * @type {ContactinformationsRequestCompound}
     * @memberof ContactRequestCompound
     */
    objContactinformations:ContactinformationsRequestCompound 
}


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectContactinformationsRequestCompound } from './'
// @ts-ignore
import { ValidationObjectContactinformationsRequestCompound } from './'

/**
 * @export 
 * A ContactRequestCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectContactRequestCompound
 */
export class DataObjectContactRequestCompound {
    fkiContacttitleID:number = 0
    fkiLanguageID:number = 0
    sContactFirstname:string = ''
    sContactLastname:string = ''
    sContactCompany:string = ''
    dtContactBirthdate?:string = undefined
    objContactinformations:ContactinformationsRequestCompound = new DataObjectContactinformationsRequestCompound()
}

/**
 * @export 
 * A ContactRequestCompound Validation Object
 * @class ValidationObjectContactRequestCompound
 */
export class ValidationObjectContactRequestCompound {
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
   objContactinformations = new ValidationObjectContactinformationsRequestCompound()
} 


