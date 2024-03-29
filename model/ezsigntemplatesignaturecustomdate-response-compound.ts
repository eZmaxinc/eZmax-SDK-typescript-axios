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
import { EzsigntemplatesignaturecustomdateResponse } from './ezsigntemplatesignaturecustomdate-response';

/**
 * @type EzsigntemplatesignaturecustomdateResponseCompound
 * An Ezsigntemplatesignaturecustomdate Object and children to create a complete structure
 * @export
 */
export type EzsigntemplatesignaturecustomdateResponseCompound = EzsigntemplatesignaturecustomdateResponse;


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsigntemplatesignaturecustomdateResponseCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplatesignaturecustomdateResponseCompound
 */
export class DataObjectEzsigntemplatesignaturecustomdateResponseCompound {
    pkiEzsigntemplatesignaturecustomdateID:number = 0
    iEzsigntemplatesignaturecustomdateX:number = 0
    iEzsigntemplatesignaturecustomdateY:number = 0
    sEzsigntemplatesignaturecustomdateFormat:string = ''
}

/**
 * @export 
 * A EzsigntemplatesignaturecustomdateResponseCompound Validation Object
 * @class ValidationObjectEzsigntemplatesignaturecustomdateResponseCompound
 */
export class ValidationObjectEzsigntemplatesignaturecustomdateResponseCompound {
   pkiEzsigntemplatesignaturecustomdateID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   iEzsigntemplatesignaturecustomdateX = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   iEzsigntemplatesignaturecustomdateY = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   sEzsigntemplatesignaturecustomdateFormat = {
      type: 'string',
      required: true
   }
} 


