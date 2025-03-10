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
import type { EzsignsignergroupResponse } from './ezsignsignergroup-response';
// May contain unused imports in some cases
// @ts-ignore
import type { MultilingualEzsignsignergroupDescription } from './multilingual-ezsignsignergroup-description';

/**
 * @type EzsignsignergroupResponseCompound
 * An Ezsignsignergroup Object
 * @export
 */
/*export type EzsignsignergroupResponseCompound = EzsignsignergroupResponse;*/
export interface EzsignsignergroupResponseCompound {
    /**
     * The unique ID of the Ezsignsignergroup
     * @type {number}
     * @memberof EzsignsignergroupResponseCompound
     */
    pkiEzsignsignergroupID:number 
    /**
     * 
     * @type {MultilingualEzsignsignergroupDescription}
     * @memberof EzsignsignergroupResponseCompound
     */
    objEzsignsignergroupDescription:MultilingualEzsignsignergroupDescription 
    /**
     * The Description of the Ezsignsignergroup in the language of the requester
     * @type {string}
     * @memberof EzsignsignergroupResponseCompound
     */
    sEzsignsignergroupDescriptionX?:string 
}


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectMultilingualEzsignsignergroupDescription } from './'
// @ts-ignore
import { ValidationObjectMultilingualEzsignsignergroupDescription } from './'

/**
 * @export 
 * A EzsignsignergroupResponseCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignsignergroupResponseCompound
 */
export class DataObjectEzsignsignergroupResponseCompound {
    pkiEzsignsignergroupID:number = 0
    objEzsignsignergroupDescription:MultilingualEzsignsignergroupDescription = new DataObjectMultilingualEzsignsignergroupDescription()
    sEzsignsignergroupDescriptionX?:string = undefined
}

/**
 * @export 
 * A EzsignsignergroupResponseCompound Validation Object
 * @class ValidationObjectEzsignsignergroupResponseCompound
 */
export class ValidationObjectEzsignsignergroupResponseCompound {
   pkiEzsignsignergroupID = {
      type: 'integer',
      minimum: 0,
      maximum: 65535,
      required: true
   }
   objEzsignsignergroupDescription = new ValidationObjectMultilingualEzsignsignergroupDescription()
   sEzsignsignergroupDescriptionX = {
      type: 'string',
      required: false
   }
} 


