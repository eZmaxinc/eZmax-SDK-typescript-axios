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
import type { EzsignsignergroupRequest } from './ezsignsignergroup-request';
// May contain unused imports in some cases
// @ts-ignore
import type { MultilingualEzsignsignergroupDescription } from './multilingual-ezsignsignergroup-description';

/**
 * @type EzsignsignergroupRequestCompound
 * A Ezsignsignergroup Object and children
 * @export
 */
/*export type EzsignsignergroupRequestCompound = EzsignsignergroupRequest;*/
export interface EzsignsignergroupRequestCompound {
    /**
     * The unique ID of the Ezsignsignergroup
     * @type {number}
     * @memberof EzsignsignergroupRequestCompound
     */
    pkiEzsignsignergroupID?:number 
    /**
     * The unique ID of the Ezsignfolder
     * @type {number}
     * @memberof EzsignsignergroupRequestCompound
     */
    fkiEzsignfolderID:number 
    /**
     * 
     * @type {MultilingualEzsignsignergroupDescription}
     * @memberof EzsignsignergroupRequestCompound
     */
    objEzsignsignergroupDescription:MultilingualEzsignsignergroupDescription 
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
 * A EzsignsignergroupRequestCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignsignergroupRequestCompound
 */
export class DataObjectEzsignsignergroupRequestCompound {
    pkiEzsignsignergroupID?:number = undefined
    fkiEzsignfolderID:number = 0
    objEzsignsignergroupDescription:MultilingualEzsignsignergroupDescription = new DataObjectMultilingualEzsignsignergroupDescription()
}

/**
 * @export 
 * A EzsignsignergroupRequestCompound Validation Object
 * @class ValidationObjectEzsignsignergroupRequestCompound
 */
export class ValidationObjectEzsignsignergroupRequestCompound {
   pkiEzsignsignergroupID = {
      type: 'integer',
      minimum: 0,
      maximum: 65535,
      required: false
   }
   fkiEzsignfolderID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   objEzsignsignergroupDescription = new ValidationObjectMultilingualEzsignsignergroupDescription()
} 


