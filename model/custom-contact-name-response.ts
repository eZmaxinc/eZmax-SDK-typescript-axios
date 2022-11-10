/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.16
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



import { DefaultObject } from '../base'

/**
 * A Custom ContactName Object
 * @export
 * @interface CustomContactNameResponse
 */
export interface CustomContactNameResponse {
    /**
     * The First name of the contact
     * @type {string}
     * @memberof CustomContactNameResponse
     */
    'sContactFirstname'?: string;
    /**
     * The Last name of the contact
     * @type {string}
     * @memberof CustomContactNameResponse
     */
    'sContactLastname'?: string;
    /**
     * The Company name of the contact
     * @type {string}
     * @memberof CustomContactNameResponse
     */
    'sContactCompany'?: string;
}
/**
 * A CustomContactNameResponse Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectCustomContactNameResponse
 */
export class DefaultObjectCustomContactNameResponse extends DefaultObject {
   sContactFirstname?:string = undefined
   sContactLastname?:string = undefined
   sContactCompany?:string = undefined
}


