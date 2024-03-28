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
import { EzsignbulksendRequest } from './ezsignbulksend-request';

/**
 * @type EzsignbulksendRequestCompound
 * A Ezsignbulksend Object and children
 * @export
 */
/** export type EzsignbulksendRequestCompound = EzsignbulksendRequest; */
export interface EzsignbulksendRequestCompound {
    /**
     * The unique ID of the Ezsignbulksend
     * @type {number}
     * @memberof EzsignbulksendRequestCompound
     */
    pkiEzsignbulksendID?:number 
    /**
     * The unique ID of the Ezsignfoldertype.
     * @type {number}
     * @memberof EzsignbulksendRequestCompound
     */
    fkiEzsignfoldertypeID:number 
    /**
     * The unique ID of the Language.  Valid values:  |Value|Description| |-|-| |1|French| |2|English|
     * @type {number}
     * @memberof EzsignbulksendRequestCompound
     */
    fkiLanguageID:number 
    /**
     * The description of the Ezsignbulksend
     * @type {string}
     * @memberof EzsignbulksendRequestCompound
     */
    sEzsignbulksendDescription:string 
    /**
     * Note about the Ezsignbulksend
     * @type {string}
     * @memberof EzsignbulksendRequestCompound
     */
    tEzsignbulksendNote:string 
    /**
     * Whether the Ezsigntemplatepackage was automatically modified and needs a manual validation
     * @type {boolean}
     * @memberof EzsignbulksendRequestCompound
     */
    bEzsignbulksendNeedvalidation:boolean 
    /**
     * Whether the Ezsignbulksend is active or not
     * @type {boolean}
     * @memberof EzsignbulksendRequestCompound
     */
    bEzsignbulksendIsactive:boolean 
}


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsignbulksendRequestCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignbulksendRequestCompound
 */
export class DataObjectEzsignbulksendRequestCompound {
    pkiEzsignbulksendID?:number = undefined
    fkiEzsignfoldertypeID:number = 0
    fkiLanguageID:number = 0
    sEzsignbulksendDescription:string = ''
    tEzsignbulksendNote:string = ''
    bEzsignbulksendNeedvalidation:boolean = false
    bEzsignbulksendIsactive:boolean = false
}

/**
 * @export 
 * A EzsignbulksendRequestCompound Validation Object
 * @class ValidationObjectEzsignbulksendRequestCompound
 */
export class ValidationObjectEzsignbulksendRequestCompound {
   pkiEzsignbulksendID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   fkiEzsignfoldertypeID = {
      type: 'integer',
      minimum: 0,
      maximum: 65535,
      required: true
   }
   fkiLanguageID = {
      type: 'integer',
      minimum: 1,
      maximum: 2,
      required: true
   }
   sEzsignbulksendDescription = {
      type: 'string',
      required: true
   }
   tEzsignbulksendNote = {
      type: 'string',
      required: true
   }
   bEzsignbulksendNeedvalidation = {
      type: 'boolean',
      required: true
   }
   bEzsignbulksendIsactive = {
      type: 'boolean',
      required: true
   }
} 


