/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.7
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


import { EzsigntemplateResponseCompound } from './ezsigntemplate-response-compound';
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

