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
import { EzsigntemplatedocumentGetEzsigntemplateformfieldgroupsV1ResponseMPayload } from './ezsigntemplatedocument-get-ezsigntemplateformfieldgroups-v1-response-mpayload';

import { DefaultObject } from '../base'

/**
 * 
 * @export
 * @interface EzsigntemplatedocumentGetEzsigntemplateformfieldgroupsV1ResponseAllOf
 */
export interface EzsigntemplatedocumentGetEzsigntemplateformfieldgroupsV1ResponseAllOf {
    /**
     * 
     * @type {EzsigntemplatedocumentGetEzsigntemplateformfieldgroupsV1ResponseMPayload}
     * @memberof EzsigntemplatedocumentGetEzsigntemplateformfieldgroupsV1ResponseAllOf
     */
    'mPayload': EzsigntemplatedocumentGetEzsigntemplateformfieldgroupsV1ResponseMPayload;
}
/**
 * A EzsigntemplatedocumentGetEzsigntemplateformfieldgroupsV1ResponseAllOf Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsigntemplatedocumentGetEzsigntemplateformfieldgroupsV1ResponseAllOf
 */
export class DefaultObjectEzsigntemplatedocumentGetEzsigntemplateformfieldgroupsV1ResponseAllOf extends DefaultObject {
   mPayload:Partial<EzsigntemplatedocumentGetEzsigntemplateformfieldgroupsV1ResponseMPayload> = {}
}


