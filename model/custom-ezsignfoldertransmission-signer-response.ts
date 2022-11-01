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



import { DefaultObject } from '../base'

/**
 * A form Signer Object in the context of an Ezsignfoldertransmissions
 * @export
 * @interface CustomEzsignfoldertransmissionSignerResponse
 */
export interface CustomEzsignfoldertransmissionSignerResponse {
    /**
     * The unique ID of the User
     * @type {number}
     * @memberof CustomEzsignfoldertransmissionSignerResponse
     */
    'fkiUserID'?: number;
    /**
     * The First name of the contact
     * @type {string}
     * @memberof CustomEzsignfoldertransmissionSignerResponse
     */
    'sContactFirstname': string;
    /**
     * The Last name of the contact
     * @type {string}
     * @memberof CustomEzsignfoldertransmissionSignerResponse
     */
    'sContactLastname': string;
}
/**
 * A CustomEzsignfoldertransmissionSignerResponse Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectCustomEzsignfoldertransmissionSignerResponse
 */
export class DefaultObjectCustomEzsignfoldertransmissionSignerResponse extends DefaultObject {
   fkiUserID?:number = undefined
   sContactFirstname:string = ''
   sContactLastname:string = ''
}


