/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.12
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { EzsigntemplateformfieldgroupRequestCompound } from './ezsigntemplateformfieldgroup-request-compound';

import { DefaultObject } from '../base'

/**
 * Request for PUT /1/object/ezsigntemplatedocument/{pkiEzsigntemplatedocumentID}/editEzsigntemplateformfieldgroups
 * @export
 * @interface EzsigntemplatedocumentEditEzsigntemplateformfieldgroupsV1Request
 */
export interface EzsigntemplatedocumentEditEzsigntemplateformfieldgroupsV1Request {
    /**
     * 
     * @type {Array<EzsigntemplateformfieldgroupRequestCompound>}
     * @memberof EzsigntemplatedocumentEditEzsigntemplateformfieldgroupsV1Request
     */
    'a_objEzsigntemplateformfieldgroup': Array<EzsigntemplateformfieldgroupRequestCompound>;
}
/**
 * A EzsigntemplatedocumentEditEzsigntemplateformfieldgroupsV1Request Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsigntemplatedocumentEditEzsigntemplateformfieldgroupsV1Request
 */
export class DefaultObjectEzsigntemplatedocumentEditEzsigntemplateformfieldgroupsV1Request extends DefaultObject {
   a_objEzsigntemplateformfieldgroup:Array<EzsigntemplateformfieldgroupRequestCompound> = []
}


