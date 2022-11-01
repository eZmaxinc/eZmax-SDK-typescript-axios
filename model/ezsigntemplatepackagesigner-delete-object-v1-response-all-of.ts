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
import { EzsigntemplatepackagesignerDeleteObjectV1ResponseMPayload } from './ezsigntemplatepackagesigner-delete-object-v1-response-mpayload';

import { DefaultObject } from '../base'

/**
 * 
 * @export
 * @interface EzsigntemplatepackagesignerDeleteObjectV1ResponseAllOf
 */
export interface EzsigntemplatepackagesignerDeleteObjectV1ResponseAllOf {
    /**
     * 
     * @type {EzsigntemplatepackagesignerDeleteObjectV1ResponseMPayload}
     * @memberof EzsigntemplatepackagesignerDeleteObjectV1ResponseAllOf
     */
    'mPayload': EzsigntemplatepackagesignerDeleteObjectV1ResponseMPayload;
}
/**
 * A EzsigntemplatepackagesignerDeleteObjectV1ResponseAllOf Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsigntemplatepackagesignerDeleteObjectV1ResponseAllOf
 */
export class DefaultObjectEzsigntemplatepackagesignerDeleteObjectV1ResponseAllOf extends DefaultObject {
   mPayload:Partial<EzsigntemplatepackagesignerDeleteObjectV1ResponseMPayload> = {}
}


