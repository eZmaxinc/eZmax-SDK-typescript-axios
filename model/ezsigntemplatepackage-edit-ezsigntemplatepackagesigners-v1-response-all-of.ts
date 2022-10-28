/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.13
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { EzsigntemplatepackageEditEzsigntemplatepackagesignersV1ResponseMPayload } from './ezsigntemplatepackage-edit-ezsigntemplatepackagesigners-v1-response-mpayload';

import { DefaultObject } from '../base'

/**
 * 
 * @export
 * @interface EzsigntemplatepackageEditEzsigntemplatepackagesignersV1ResponseAllOf
 */
export interface EzsigntemplatepackageEditEzsigntemplatepackagesignersV1ResponseAllOf {
    /**
     * 
     * @type {EzsigntemplatepackageEditEzsigntemplatepackagesignersV1ResponseMPayload}
     * @memberof EzsigntemplatepackageEditEzsigntemplatepackagesignersV1ResponseAllOf
     */
    'mPayload': EzsigntemplatepackageEditEzsigntemplatepackagesignersV1ResponseMPayload;
}
/**
 * A EzsigntemplatepackageEditEzsigntemplatepackagesignersV1ResponseAllOf Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsigntemplatepackageEditEzsigntemplatepackagesignersV1ResponseAllOf
 */
export class DefaultObjectEzsigntemplatepackageEditEzsigntemplatepackagesignersV1ResponseAllOf extends DefaultObject {
   mPayload:Partial<EzsigntemplatepackageEditEzsigntemplatepackagesignersV1ResponseMPayload> = {}
}


