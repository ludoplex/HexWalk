#ifndef COLORTAG_H
#define COLORTAG_H

#include <QString>
typedef enum TagType_e
{
    STRING_t,
    BE_t,
    LE_t
}TagType_e;

class ColorTag{
public:
    QString name;
    int64_t pos;
    int64_t size;
    QString color;
    TagType_e type;
};


#endif // COLORTAG_H
