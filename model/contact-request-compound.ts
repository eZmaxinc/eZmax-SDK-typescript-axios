/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.14
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
import { ContactRequestCompoundAllOf } from './contact-request-compound-all-of';
// May contain unused imports in some cases
// @ts-ignore
import { ContactinformationsRequestCompound } from './contactinformations-request-compound';

import { DefaultObject } from '../base'

/**
 * @type ContactRequestCompound
 * A Contact Object and children to create a complete structure
 * @export
 */
export type ContactRequestCompound = ContactRequest & ContactRequestCompoundAllOf;


/**
 * @export 
 * A ContactRequestCompound Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @class DefaultObjectContactRequestCompound
 */
export class DefaultObjectContactRequestCompound extends DefaultObject {
   fkiContacttitleID:number = 0
   fkiLanguageID:number = 0
   sContactFirstname:string = ''
   sContactLastname:string = ''
   sContactCompany:string = ''
   dtContactBirthdate?:string = undefined
   objContactinformations:Partial<ContactinformationsRequestCompound> = {}
}


