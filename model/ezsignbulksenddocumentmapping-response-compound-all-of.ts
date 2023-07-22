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
import { EzsigntemplateResponseCompound } from './ezsigntemplate-response-compound';
// May contain unused imports in some cases
// @ts-ignore
import { EzsigntemplatepackageResponseCompound } from './ezsigntemplatepackage-response-compound';

/**
 * 
 * @export
 * @interface EzsignbulksenddocumentmappingResponseCompoundAllOf
 */
export interface EzsignbulksenddocumentmappingResponseCompoundAllOf {
    /**
     * 
     * @type {EzsigntemplateResponseCompound}
     * @memberof EzsignbulksenddocumentmappingResponseCompoundAllOf
     */
    'objEzsigntemplate'?: EzsigntemplateResponseCompound;
    /**
     * 
     * @type {EzsigntemplatepackageResponseCompound}
     * @memberof EzsignbulksenddocumentmappingResponseCompoundAllOf
     */
    'objEzsigntemplatepackage'?: EzsigntemplatepackageResponseCompound;
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
 * A EzsignbulksenddocumentmappingResponseCompoundAllOf Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignbulksenddocumentmappingResponseCompoundAllOf
 */
export class DataObjectEzsignbulksenddocumentmappingResponseCompoundAllOf {
   objEzsigntemplate?:EzsigntemplateResponseCompound = undefined
   objEzsigntemplatepackage?:EzsigntemplatepackageResponseCompound = undefined
}

/**
 * @export 
 * A EzsignbulksenddocumentmappingResponseCompoundAllOf Validation Object
 * @class ValidationObjectEzsignbulksenddocumentmappingResponseCompoundAllOf
 */
export class ValidationObjectEzsignbulksenddocumentmappingResponseCompoundAllOf {
   objEzsigntemplate = new ValidationObjectEzsigntemplateResponseCompound()
   objEzsigntemplatepackage = new ValidationObjectEzsigntemplatepackageResponseCompound()
} 


