/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.17
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { EzsignbulksenddocumentmappingResponse } from './ezsignbulksenddocumentmapping-response';
// May contain unused imports in some cases
// @ts-ignore
import { EzsignbulksenddocumentmappingResponseCompoundAllOf } from './ezsignbulksenddocumentmapping-response-compound-all-of';
// May contain unused imports in some cases
// @ts-ignore
import { EzsigntemplateResponseCompound } from './ezsigntemplate-response-compound';
// May contain unused imports in some cases
// @ts-ignore
import { EzsigntemplatepackageResponseCompound } from './ezsigntemplatepackage-response-compound';

import { DefaultObject } from '../base'

/**
 * @type EzsignbulksenddocumentmappingResponseCompound
 * A Ezsignbulksenddocumentmapping Object
 * @export
 */
export type EzsignbulksenddocumentmappingResponseCompound = EzsignbulksenddocumentmappingResponse & EzsignbulksenddocumentmappingResponseCompoundAllOf;


/**
 * @export 
 * A EzsignbulksenddocumentmappingResponseCompound Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @class DefaultObjectEzsignbulksenddocumentmappingResponseCompound
 */
export class DefaultObjectEzsignbulksenddocumentmappingResponseCompound extends DefaultObject {
   pkiEzsignbulksenddocumentmappingID:number = 0
   fkiEzsignbulksendID:number = 0
   fkiEzsigntemplatepackageID?:number = undefined
   fkiEzsigntemplateID?:number = undefined
   iEzsignbulksenddocumentmappingOrder:number = 0
   objEzsigntemplate?:Partial<EzsigntemplateResponseCompound> = undefined
   objEzsigntemplatepackage?:Partial<EzsigntemplatepackageResponseCompound> = undefined
}


