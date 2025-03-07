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
import type { EzsignsigningreasonResponse } from './ezsignsigningreason-response';
// May contain unused imports in some cases
// @ts-ignore
import type { MultilingualEzsignsigningreasonDescription } from './multilingual-ezsignsigningreason-description';

/**
 * @type EzsignsigningreasonResponseCompound
 * A Ezsignsigningreason Object
 * @export
 */
/*export type EzsignsigningreasonResponseCompound = EzsignsigningreasonResponse;*/
export interface EzsignsigningreasonResponseCompound {
    /**
     * The unique ID of the Ezsignsigningreason
     * @type {number}
     * @memberof EzsignsigningreasonResponseCompound
     */
    pkiEzsignsigningreasonID:number 
    /**
     * 
     * @type {MultilingualEzsignsigningreasonDescription}
     * @memberof EzsignsigningreasonResponseCompound
     */
    objEzsignsigningreasonDescription:MultilingualEzsignsigningreasonDescription 
    /**
     * Whether the ezsignsigningreason is active or not
     * @type {boolean}
     * @memberof EzsignsigningreasonResponseCompound
     */
    bEzsignsigningreasonIsactive:boolean 
}


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectMultilingualEzsignsigningreasonDescription } from './'
// @ts-ignore
import { ValidationObjectMultilingualEzsignsigningreasonDescription } from './'

/**
 * @export 
 * A EzsignsigningreasonResponseCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignsigningreasonResponseCompound
 */
export class DataObjectEzsignsigningreasonResponseCompound {
    pkiEzsignsigningreasonID:number = 0
    objEzsignsigningreasonDescription:MultilingualEzsignsigningreasonDescription = new DataObjectMultilingualEzsignsigningreasonDescription()
    bEzsignsigningreasonIsactive:boolean = false
}

/**
 * @export 
 * A EzsignsigningreasonResponseCompound Validation Object
 * @class ValidationObjectEzsignsigningreasonResponseCompound
 */
export class ValidationObjectEzsignsigningreasonResponseCompound {
   pkiEzsignsigningreasonID = {
      type: 'integer',
      minimum: 0,
      maximum: 255,
      required: true
   }
   objEzsignsigningreasonDescription = new ValidationObjectMultilingualEzsignsigningreasonDescription()
   bEzsignsigningreasonIsactive = {
      type: 'boolean',
      required: true
   }
} 


