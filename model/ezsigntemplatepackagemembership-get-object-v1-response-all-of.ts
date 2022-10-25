/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.11
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { EzsigntemplatepackagemembershipGetObjectV1ResponseMPayload } from './ezsigntemplatepackagemembership-get-object-v1-response-mpayload';

import { DefaultObject } from '../base'

/**
 * 
 * @export
 * @interface EzsigntemplatepackagemembershipGetObjectV1ResponseAllOf
 */
export interface EzsigntemplatepackagemembershipGetObjectV1ResponseAllOf {
    /**
     * 
     * @type {EzsigntemplatepackagemembershipGetObjectV1ResponseMPayload}
     * @memberof EzsigntemplatepackagemembershipGetObjectV1ResponseAllOf
     */
    'mPayload': EzsigntemplatepackagemembershipGetObjectV1ResponseMPayload;
}
/**
 * A EzsigntemplatepackagemembershipGetObjectV1ResponseAllOf Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsigntemplatepackagemembershipGetObjectV1ResponseAllOf
 */
export class DefaultObjectEzsigntemplatepackagemembershipGetObjectV1ResponseAllOf extends DefaultObject {
   mPayload:Partial<EzsigntemplatepackagemembershipGetObjectV1ResponseMPayload> = {}
}


