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


// May contain unused imports in some cases
// @ts-ignore
import { EzsignsignaturecustomdateRequest } from './ezsignsignaturecustomdate-request';

/**
 * @type EzsignsignaturecustomdateRequestCompound
 * An Ezsignsignaturecustomdate Object and children to create a complete structure
 * @export
 */
export type EzsignsignaturecustomdateRequestCompound = EzsignsignaturecustomdateRequest;


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsignsignaturecustomdateRequestCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignsignaturecustomdateRequestCompound
 */
export class DataObjectEzsignsignaturecustomdateRequestCompound {
    pkiEzsignsignaturecustomdateID?:number = undefined
    iEzsignsignaturecustomdateX:number = 0
    iEzsignsignaturecustomdateY:number = 0
    sEzsignsignaturecustomdateFormat:string = ''
}

/**
 * @export 
 * A EzsignsignaturecustomdateRequestCompound Validation Object
 * @class ValidationObjectEzsignsignaturecustomdateRequestCompound
 */
export class ValidationObjectEzsignsignaturecustomdateRequestCompound {
   pkiEzsignsignaturecustomdateID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   iEzsignsignaturecustomdateX = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   iEzsignsignaturecustomdateY = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   sEzsignsignaturecustomdateFormat = {
      type: 'string',
      required: true
   }
} 


