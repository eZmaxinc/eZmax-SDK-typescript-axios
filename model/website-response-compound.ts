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
import type { WebsiteResponse } from './website-response';

/**
 * @type WebsiteResponseCompound
 * A Website Object and children to create a complete structure
 * @export
 */
/*export type WebsiteResponseCompound = WebsiteResponse;*/
export interface WebsiteResponseCompound {
    /**
     * The unique ID of the Website Default
     * @type {number}
     * @memberof WebsiteResponseCompound
     */
    pkiWebsiteID:number 
    /**
     * The unique ID of the Websitetype.  Valid values:  |Value|Description| |-|-| |1|Website| |2|Twitter| |3|Facebook| |4|Survey|
     * @type {number}
     * @memberof WebsiteResponseCompound
     */
    fkiWebsitetypeID:number 
    /**
     * The URL of the website.
     * @type {string}
     * @memberof WebsiteResponseCompound
     */
    sWebsiteAddress:string 
}


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A WebsiteResponseCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectWebsiteResponseCompound
 */
export class DataObjectWebsiteResponseCompound {
    pkiWebsiteID:number = 0
    fkiWebsitetypeID:number = 0
    sWebsiteAddress:string = ''
}

/**
 * @export 
 * A WebsiteResponseCompound Validation Object
 * @class ValidationObjectWebsiteResponseCompound
 */
export class ValidationObjectWebsiteResponseCompound {
   pkiWebsiteID = {
      type: 'integer',
      minimum: 0,
      maximum: 16777215,
      required: true
   }
   fkiWebsitetypeID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   sWebsiteAddress = {
      type: 'string',
      required: true
   }
} 


