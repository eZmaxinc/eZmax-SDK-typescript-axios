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
import { EzsigntemplatepackagesignerResponseCompound } from './ezsigntemplatepackagesigner-response-compound';

import { DefaultObject } from '../base'

/**
 * Payload for GET /2/object/ezsigntemplatepackagesigner/{pkiEzsigntemplatepackagesignerID}
 * @export
 * @interface EzsigntemplatepackagesignerGetObjectV2ResponseMPayload
 */
export interface EzsigntemplatepackagesignerGetObjectV2ResponseMPayload {
    /**
     * 
     * @type {EzsigntemplatepackagesignerResponseCompound}
     * @memberof EzsigntemplatepackagesignerGetObjectV2ResponseMPayload
     */
    'objEzsigntemplatepackagesigner': EzsigntemplatepackagesignerResponseCompound;
}
/**
 * A EzsigntemplatepackagesignerGetObjectV2ResponseMPayload Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsigntemplatepackagesignerGetObjectV2ResponseMPayload
 */
export class DefaultObjectEzsigntemplatepackagesignerGetObjectV2ResponseMPayload extends DefaultObject {
   objEzsigntemplatepackagesigner:Partial<EzsigntemplatepackagesignerResponseCompound> = {}
}


