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
import type { EzsignbulksenddocumentmappingResponse } from './ezsignbulksenddocumentmapping-response';
// May contain unused imports in some cases
// @ts-ignore
import type { EzsigntemplateResponseCompound } from './ezsigntemplate-response-compound';
// May contain unused imports in some cases
// @ts-ignore
import type { EzsigntemplatepackageResponseCompound } from './ezsigntemplatepackage-response-compound';

/**
 * @type EzsignbulksenddocumentmappingResponseCompound
 * A Ezsignbulksenddocumentmapping Object
 * @export
 */
/*export type EzsignbulksenddocumentmappingResponseCompound = EzsignbulksenddocumentmappingResponse;*/
export interface EzsignbulksenddocumentmappingResponseCompound {
    /**
     * The unique ID of the Ezsignbulksenddocumentmapping.
     * @type {number}
     * @memberof EzsignbulksenddocumentmappingResponseCompound
     */
    pkiEzsignbulksenddocumentmappingID:number 
    /**
     * The unique ID of the Ezsignbulksend
     * @type {number}
     * @memberof EzsignbulksenddocumentmappingResponseCompound
     */
    fkiEzsignbulksendID:number 
    /**
     * The unique ID of the Ezsigntemplatepackage
     * @type {number}
     * @memberof EzsignbulksenddocumentmappingResponseCompound
     */
    fkiEzsigntemplatepackageID?:number 
    /**
     * The unique ID of the Ezsigntemplate
     * @type {number}
     * @memberof EzsignbulksenddocumentmappingResponseCompound
     */
    fkiEzsigntemplateID?:number 
    /**
     * The order in which the Ezsigntemplate or Ezsigntemplatepackage will be presented to the signatory in the Ezsignfolder.
     * @type {number}
     * @memberof EzsignbulksenddocumentmappingResponseCompound
     */
    iEzsignbulksenddocumentmappingOrder:number 
    /**
     * 
     * @type {EzsigntemplateResponseCompound}
     * @memberof EzsignbulksenddocumentmappingResponseCompound
     */
    objEzsigntemplate?:EzsigntemplateResponseCompound 
    /**
     * 
     * @type {EzsigntemplatepackageResponseCompound}
     * @memberof EzsignbulksenddocumentmappingResponseCompound
     */
    objEzsigntemplatepackage?:EzsigntemplatepackageResponseCompound 
}


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEzsigntemplateResponseCompound } from './'
// @ts-ignore
import { DataObjectEzsigntemplatepackageResponseCompound } from './'
// @ts-ignore
import { ValidationObjectEzsigntemplateResponseCompound } from './'
// @ts-ignore
import { ValidationObjectEzsigntemplatepackageResponseCompound } from './'

/**
 * @export 
 * A EzsignbulksenddocumentmappingResponseCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignbulksenddocumentmappingResponseCompound
 */
export class DataObjectEzsignbulksenddocumentmappingResponseCompound {
    pkiEzsignbulksenddocumentmappingID:number = 0
    fkiEzsignbulksendID:number = 0
    fkiEzsigntemplatepackageID?:number = undefined
    fkiEzsigntemplateID?:number = undefined
    iEzsignbulksenddocumentmappingOrder:number = 0
    objEzsigntemplate?:EzsigntemplateResponseCompound = undefined
    objEzsigntemplatepackage?:EzsigntemplatepackageResponseCompound = undefined
}

/**
 * @export 
 * A EzsignbulksenddocumentmappingResponseCompound Validation Object
 * @class ValidationObjectEzsignbulksenddocumentmappingResponseCompound
 */
export class ValidationObjectEzsignbulksenddocumentmappingResponseCompound {
   pkiEzsignbulksenddocumentmappingID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   fkiEzsignbulksendID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   fkiEzsigntemplatepackageID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   fkiEzsigntemplateID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   iEzsignbulksenddocumentmappingOrder = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   objEzsigntemplate = new ValidationObjectEzsigntemplateResponseCompound()
   objEzsigntemplatepackage = new ValidationObjectEzsigntemplatepackageResponseCompound()
} 


