/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.14
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { EzsigntemplatedocumentResponse } from './ezsigntemplatedocument-response';
// May contain unused imports in some cases
// @ts-ignore
import { EzsigntemplatesignerResponseCompound } from './ezsigntemplatesigner-response-compound';

import { DefaultObject } from '../base'

/**
 * 
 * @export
 * @interface EzsigntemplateResponseCompoundAllOf
 */
export interface EzsigntemplateResponseCompoundAllOf {
    /**
     * 
     * @type {EzsigntemplatedocumentResponse}
     * @memberof EzsigntemplateResponseCompoundAllOf
     */
    'objEzsigntemplatedocument'?: EzsigntemplatedocumentResponse;
    /**
     * 
     * @type {Array<EzsigntemplatesignerResponseCompound>}
     * @memberof EzsigntemplateResponseCompoundAllOf
     */
    'a_objEzsigntemplatesigner': Array<EzsigntemplatesignerResponseCompound>;
}
/**
 * A EzsigntemplateResponseCompoundAllOf Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsigntemplateResponseCompoundAllOf
 */
export class DefaultObjectEzsigntemplateResponseCompoundAllOf extends DefaultObject {
   objEzsigntemplatedocument?:Partial<EzsigntemplatedocumentResponse> = undefined
   a_objEzsigntemplatesigner:Array<EzsigntemplatesignerResponseCompound> = []
}


