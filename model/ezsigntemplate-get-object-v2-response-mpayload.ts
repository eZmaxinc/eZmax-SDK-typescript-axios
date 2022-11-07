/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.15
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { EzsigntemplateResponseCompound } from './ezsigntemplate-response-compound';

import { DefaultObject } from '../base'

/**
 * Payload for GET /2/object/ezsigntemplate/{pkiEzsigntemplateID}
 * @export
 * @interface EzsigntemplateGetObjectV2ResponseMPayload
 */
export interface EzsigntemplateGetObjectV2ResponseMPayload {
    /**
     * 
     * @type {EzsigntemplateResponseCompound}
     * @memberof EzsigntemplateGetObjectV2ResponseMPayload
     */
    'objEzsigntemplate': EzsigntemplateResponseCompound;
}
/**
 * A EzsigntemplateGetObjectV2ResponseMPayload Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsigntemplateGetObjectV2ResponseMPayload
 */
export class DefaultObjectEzsigntemplateGetObjectV2ResponseMPayload extends DefaultObject {
   objEzsigntemplate:Partial<EzsigntemplateResponseCompound> = {}
}


