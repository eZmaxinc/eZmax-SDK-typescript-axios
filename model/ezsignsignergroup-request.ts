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
import { MultilingualEzsignsignergroupDescription } from './multilingual-ezsignsignergroup-description';

/**
 * A Ezsignsignergroup Object
 * @export
 * @interface EzsignsignergroupRequest
 */
export interface EzsignsignergroupRequest {
    /**
     * The unique ID of the Ezsignsignergroup
     * @type {number}
     * @memberof EzsignsignergroupRequest
     */
    'pkiEzsignsignergroupID'?: number;
    /**
     * The unique ID of the Ezsignfolder
     * @type {number}
     * @memberof EzsignsignergroupRequest
     */
    'fkiEzsignfolderID': number;
    /**
     * 
     * @type {MultilingualEzsignsignergroupDescription}
     * @memberof EzsignsignergroupRequest
     */
    'objEzsignsignergroupDescription': MultilingualEzsignsignergroupDescription;
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
 * A EzsignsignergroupRequest Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignsignergroupRequest
 */
export class DataObjectEzsignsignergroupRequest {
   pkiEzsignsignergroupID?:number = undefined
   fkiEzsignfolderID:number = 0
   objEzsignsignergroupDescription:MultilingualEzsignsignergroupDescription = new DataObjectMultilingualEzsignsignergroupDescription()
}

/**
 * @export 
 * A EzsignsignergroupRequest Validation Object
 * @class ValidationObjectEzsignsignergroupRequest
 */
export class ValidationObjectEzsignsignergroupRequest {
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


