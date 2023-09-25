/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.0
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { EzsigntemplatesignerRequest } from './ezsigntemplatesigner-request';

/**
 * @type EzsigntemplatesignerRequestCompound
 * A Ezsigntemplatesigner Object and children
 * @export
 */
/** export type EzsigntemplatesignerRequestCompound = EzsigntemplatesignerRequest; */
export interface EzsigntemplatesignerRequestCompound {
    /**
     * The unique ID of the Ezsigntemplatesigner
     * @type {number}
     * @memberof EzsigntemplatesignerRequestCompound
     */
    pkiEzsigntemplatesignerID?:number 
    /**
     * The unique ID of the Ezsigntemplate
     * @type {number}
     * @memberof EzsigntemplatesignerRequestCompound
     */
    fkiEzsigntemplateID:number 
    /**
     * The description of the Ezsigntemplatesigner
     * @type {string}
     * @memberof EzsigntemplatesignerRequestCompound
     */
    sEzsigntemplatesignerDescription:string 
}


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsigntemplatesignerRequestCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplatesignerRequestCompound
 */
export class DataObjectEzsigntemplatesignerRequestCompound {
    pkiEzsigntemplatesignerID?:number = undefined
    fkiEzsigntemplateID:number = 0
    sEzsigntemplatesignerDescription:string = ''
}

/**
 * @export 
 * A EzsigntemplatesignerRequestCompound Validation Object
 * @class ValidationObjectEzsigntemplatesignerRequestCompound
 */
export class ValidationObjectEzsigntemplatesignerRequestCompound {
   pkiEzsigntemplatesignerID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   fkiEzsigntemplateID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   sEzsigntemplatesignerDescription = {
      type: 'string',
      required: true
   }
} 


