/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.2
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import type { DomainRequest } from './domain-request';

/**
 * @type DomainRequestCompound
 * A Domain Object and children
 * @export
 */
/*export type DomainRequestCompound = DomainRequest;*/
export interface DomainRequestCompound {
    /**
     * The unique ID of the Domain
     * @type {number}
     * @memberof DomainRequestCompound
     */
    pkiDomainID?:number 
    /**
     * The name of the Domain
     * @type {string}
     * @memberof DomainRequestCompound
     */
    sDomainName:string 
}


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A DomainRequestCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectDomainRequestCompound
 */
export class DataObjectDomainRequestCompound {
    pkiDomainID?:number = undefined
    sDomainName:string = ''
}

/**
 * @export 
 * A DomainRequestCompound Validation Object
 * @class ValidationObjectDomainRequestCompound
 */
export class ValidationObjectDomainRequestCompound {
   pkiDomainID = {
      type: 'integer',
      minimum: 0,
      maximum: 255,
      required: false
   }
   sDomainName = {
      type: 'string',
      pattern: /^(?=.{4,75}$)([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,63}$/,
      required: true
   }
} 


