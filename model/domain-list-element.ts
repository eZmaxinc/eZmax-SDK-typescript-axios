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



/**
 * A Domain List Element
 * @export
 * @interface DomainListElement
 */
export interface DomainListElement {
    /**
     * The unique ID of the Domain
     * @type {number}
     * @memberof DomainListElement
     */
    /*'pkiDomainID': number;*/
    'pkiDomainID': number;
    /**
     * The name of the Domain
     * @type {string}
     * @memberof DomainListElement
     */
    /*'sDomainName': string;*/
    'sDomainName': string;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A DomainListElement Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectDomainListElement
 */
export class DataObjectDomainListElement {
   pkiDomainID:number = 0
   sDomainName:string = ''
}

/**
 * @export 
 * A DomainListElement Validation Object
 * @class ValidationObjectDomainListElement
 */
export class ValidationObjectDomainListElement {
   pkiDomainID = {
      type: 'integer',
      minimum: 0,
      maximum: 255,
      required: true
   }
   sDomainName = {
      type: 'string',
      pattern: /^(?=.{4,75}$)([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,63}$/,
      required: true
   }
} 


